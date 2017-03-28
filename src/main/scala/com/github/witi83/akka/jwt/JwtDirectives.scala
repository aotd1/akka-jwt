package com.github.witi83.akka.jwt

import java.text.ParseException
import java.time.Instant
import java.util.Date

import akka.http.scaladsl.server.{AuthorizationFailedRejection, Directive1}
import akka.http.scaladsl.server.Directives._

import com.nimbusds.jose.crypto.{MACSigner, MACVerifier}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader, JWSObject, Payload}
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTClaimsSet.Builder
import net.minidev.json.JSONObject

import scala.concurrent.ExecutionContext
import scala.language.implicitConversions
import scala.util.Try

/**
 * Provides utilities for signing and verification by the JSON Web Token (JWT).
 */
trait JwtDirectives {

  /**
   * An `AsyncAuthenticator` which returns a JWS object.
   *
   * Useful if combined with `BasicAuth` and an `authenticate` directive.
   * An inner route of an `authenticate` directive will receive a JWS object
   * (`JWSObject`) built by `claimBuilder` and signed by `signer`.
   *
   * @param authenticator
   * The `AsyncAuthenticator` which authenticates a given pair of a user
   * and a password.
   * @param claimBuilder
   * Builds a claim set from a result of `authenticator`.
   * @param signer
   * Signs a result of `claimBuilder`.
   * @param executionContext
   * The execution context to run a `Future` returned from `authenticator`.
   */
  def jwtAuthenticator[T](authenticator: AsyncAuthenticator[T])
    (implicit claimBuilder: JwtClaimBuilder.SubjectExtrator[T],
              signer: JWTClaimsSet => Option[JWSObject],
              executionContext: ExecutionContext): AsyncAuthenticator[JWSObject] =
    authenticator(_) map {
      case Some(t) => claimBuilder(t) flatMap signer
      case None => None
    }

  /**
   * Verifies a token sent with an HTTP request.
   *
   * Thanks to [[JwtAuthorizationMagnet]], this directive works like the
   * following functions,
   * {{{
   * authorizeToken[T](verifier: JWTClaimsSet => Option[T])
   *   (implicit confirmer: JWSObject => Option[JWTClaimsSet]): Directive1[T]
   *
   * authorizeToken[T](extractor: Directive1[Option[JWSObject]],
   *                   verifier: JWTClaimsSet => Option[T])
   *   (implicit confirmer: JWSObject => Option[JWTClaimsSet]): Directive1[T]
   * }}}
   *
   * This directive
   *  1. Extracts a JWS from the request through `extractor`.
   *  1. Confirms the signature of the JWS and extracts the claims set by `confirmer`.
   *  1. Verifies the claims set by `verifier`.
   *  1. Supplies the result from `verifier` to the inner route.
   *
   * Rejects
   *  - if `extractor` cannot extract a JWS from the request,
   *  - or if `confirmer` cannot confirm the signature of a JWS,
   *  - or if `confirmer` cannot extract the claims set from a JWS,
   *  - or if `verifier` rejects the claims set.
   *
   */
  def authorizeToken[T](magnet: JwtAuthorizationMagnet[T]): Directive1[T] =
    magnet.extractor flatMap { jwsOpt =>
      jwsOpt flatMap { jws =>
        magnet.confirmer(jws) flatMap { token =>
          magnet.verifier(token)
        }
      } match {
        case Some(result) => provide(result)
        case _ => reject(AuthorizationFailedRejection)
      }
    }
}

/** Companion object of [[JwtDirectives]]. */
object JwtDirectives extends JwtDirectives

/**
 * Magnet that attracts parameters necessary for the `authorizeToken`
 * directive.
 *
 * @constructor
 * @tparam T
 *     Outcome type of `verifier`.
 * @param extractor
 *     Extracts a JSON Web Signature (JWS) from an HTTP request.
 * @param confirmer
 *     Confirms the signature of the JWS and extracts the claims set.
 * @param verifier
 *     Verifiers the claims set and converts it to an application-specific
 *     object.
 */
case class JwtAuthorizationMagnet[T](
  extractor: Directive1[Option[JWSObject]],
  confirmer: JWSObject => Option[JWTClaimsSet],
  verifier: JWTClaimsSet => Option[T])

/** Companion object of [[JwtAuthorizationMagnet]]. */
object JwtAuthorizationMagnet {
  /**
   * Implicitly converts a given verifier function into
   * a [[JwtAuthorizationMagnet]].
   *
   * @param verifier
   *     Returns an application-specific object if a given claims set is
   *     verified, otherwise `None`.
   */
  implicit def fromVerifier[T](verifier: JWTClaimsSet => Option[T])
    (implicit confirmer: JWSObject => Option[JWTClaimsSet]):
      JwtAuthorizationMagnet[T] = JwtAuthorizationMagnet(
        JwsExtractor.extractJwsFromAuthorizationHeader,
        confirmer,
        verifier)

  /**
    * Implicitly converts a given pair of an extractor directive and a verifier
    * function into a [[JwtAuthorizationMagnet]].
    *
    * @param ev
    *     `ev._1` extracts a JWS from an HTTP request.
    *     `ev._2` verifies a given claims set and returns an application-specific
    *     object.
    */
  implicit def fromExtractor[T](ev: (Directive1[Option[JWSObject]],
                                    JWTClaimsSet => Option[T]))
    (implicit confirmer: JWSObject => Option[JWTClaimsSet]):
      JwtAuthorizationMagnet[T] =
        JwtAuthorizationMagnet(ev._1, confirmer, ev._2)
}

/**
 * Provides signature signer and verifier for JWS.
 *
 * @param algorithm
 * Name of the signature algorithm.
 * @param secret
 * Secret key for the signature algorithm.
 */
case class JwtSignature(algorithm: JWSAlgorithm, secret: String) {
  /** Common header of JWS objects. */
  private[this] val header = new JWSHeader(algorithm)

  /** Common signer for JWS objects. */
  private[this] val signer = new MACSigner(secret.getBytes)

  /** Common verifier for JWS objects. */
  private[this] val verifier = new MACVerifier(secret.getBytes)

  /**
   * Implicit signer for JWS objects.
   *
   * Signs a given claims set and returns a signed JWS object.
   */
  implicit def jwtSigner(claim: JWTClaimsSet): JWSObject = {
    val jwsObject = new JWSObject(header, new Payload(claim.toJSONObject))
    jwsObject.sign(signer)
    jwsObject
  }

  implicit def jwtSignerOp(claim: JWTClaimsSet): Option[JWSObject] = Some(jwtSigner(claim))

  /**
   * The implicit verifier for JWS objects.
   *
   * Confirms the signature of a given JWS object and returns its claims set.
   */
  implicit def jwtVerifier(token: JWSObject): Option[JWTClaimsSet] = if (token.verify(verifier)) {
    Try(Some(JWTClaimsSet.parse(token.getPayload.toJSONObject))) getOrElse None
  } else None
}

/**
 * Claim builder.
 *
 * You can chain multiple claim builders by `&&` operator.
 */
trait JwtClaimBuilder[T] extends JwtClaimBuilder.SubjectExtrator[T] {
  self =>

  import JwtClaimBuilder.SubjectExtrator

  /**
   * Builds a claim.
   *
   * @param input
   * Input for the claim builder.
   * Usually an output from an authenticator.
   * @return
   * Claims set build from `input`.
   */
  def apply(input: T): Option[JWTClaimsSet]

  /**
   * Chains a specified claim builder function after this claim builder.
   *
   * Claims appended by `after` have precedence over the claims built by this
   * claim builder.
   *
   * @param after
   * Claim builder that appends claims after this claim builder.
   * @return
   * New claim builder which builds a claims set by this claim builder and
   * `after`.
   */
  def &&(after: SubjectExtrator[T]): SubjectExtrator[T] = input => mergeClaims(self(input), after(input))

  /**
   * Merges specified two claim sets.
   *
   * Claims in `second` have precedence over claims in `first`.
   *
   * @param first
   * First claims set.
   * @param second
   * Second claims set.
   * @return
   * New claims set that has claims in both `first` and `second`.
   * `None` if `first` or `second` is `None`.
   */
  private def mergeClaims(first: Option[JWTClaimsSet],
                          second: Option[JWTClaimsSet]): Option[JWTClaimsSet] =
    for {
      claims1 <- first
      claims2 <- second
    } yield {
      val newClaims = new JSONObject(claims1.toJSONObject)
      newClaims.merge(claims2.toJSONObject)
      JWTClaimsSet.parse(newClaims)
    }
}

object JwtClaimBuilder {

  import scala.concurrent.duration.Duration

  type SubjectExtrator[T] = T => Option[JWTClaimsSet]

  /**
   * Returns a claim builder which sets the "exp" field to an expiration time.
   *
   * @param duration
   * Valid duration of a JWT.
   * Minimum resolution is one minute.
   */
  def claimExpiration[T](duration: Duration): SubjectExtrator[T] = input => {
    val validUntil = new Date(Instant.now().plusSeconds(duration.toSeconds).toEpochMilli)
    Some(new Builder().expirationTime(validUntil).build())
  }

  /**
   * Returns a claim builder which sets the "iss" field to a specified string.
   *
   * @param issuer
   * Issuer of a JWT.
   */
  def claimIssuer[T](issuer: String): SubjectExtrator[T] = input => Some(new Builder().issuer(issuer).build())

  /**
   * Returns a claim builder which sets the "sub" field.
   *
   * @param subject
   * Extracts the subject from an input.
   */
  def claimSubject[T](subject: T => String): SubjectExtrator[T] = input => Some(new Builder().subject(subject(input)).build())

  /**
   * Implicitly converts a claim builder function into a [[JwtClaimBuilder]].
   */
  implicit def toJwtClaimBuilder[T](f: SubjectExtrator[T]): JwtClaimBuilder[T] =
    new JwtClaimBuilder[T] {
      override def apply(input: T): Option[JWTClaimsSet] = f(input)
    }
}

/** Provides common JWS extractors. */
object JwsExtractor {
  /**
    * Extracts a JWS from "Authorization" header of an HTTP request.
    *
    * A JWS should be sent through "Authorization" header like,
    * {{{
    * Authorization: Bearer JWS
    * }}}
    *
    * @return
    *     Directive that extracts a JWS from "Authorization" header of an HTTP
    *     request.
    *     This directive provides `None` if an HTTP request does not have
    *     "Authorization" header, or if the value of "Authorization" header is
    *     invalid.
    */
  val extractJwsFromAuthorizationHeader: Directive1[Option[JWSObject]] =
    optionalHeaderValueByName("Authorization") flatMap { tokenOpt =>
      provide {
        tokenOpt flatMap { token =>
          val prefix = "Bearer "
          if (token.startsWith(prefix))
            try
              Some(JWSObject.parse(token.substring(prefix.length)))
            catch {
              case _: ParseException => None
            }
          else
            None
        }
      }
    }

  /**
    * Extracts a JWS from a cookie that has a given name.
    *
    * @param name
    *     Name of a cookie from which a JWS is to be extracted.
    * @return
    *     Directive that extracts a JWS from a cookie given by `name`.
    *     This directive provides `None` if no cookie corresponding to `name`
    *     exists, or if the value of the cookie is invalid.
    */
  def extractJwsFromCookie(name: String): Directive1[Option[JWSObject]] =
    optionalCookie(name) flatMap { ckOpt =>
      provide {
        ckOpt flatMap { ck =>
          try
            Some(JWSObject.parse(ck.value))
          catch {
            case _: ParseException => None
          }
        }
      }
    }
}

/**
 * Verifies a claims set.
 *
 * Instance of this trait can be passed as a `verifier` argument of the
 * `authorizeToken` directive.
 */
trait JwtClaimVerifier extends JwtClaimVerifier.PrivilegeFunction {
  self =>

  /**
   * Verifies a given claims set.
   *
   * @param claims
   * Claims set to be verified.
   * @return
   * Verified claims set. `None` if `claims` is not verified.
   */
  def apply(claims: JWTClaimsSet): Option[JWTClaimsSet]

  /**
   * Chains a given claim verifier after this claim verifier.
   *
   * `after` will not be applied if this claim verifier fails.
   *
   * @param after
   *  Claim verifier to be applied after this claim verifier.
   * @return
   *  New claim verifier that applies this claim verifier and then `after`.
   */
  def &&[T](after: JWTClaimsSet => Option[T]): JWTClaimsSet => Option[T] = claims =>
    for {
      first <- self(claims)
      second <- after(first)
    } yield second
}

/** Companion object of [[JwtClaimVerifier]]. */
object JwtClaimVerifier {
  type PrivilegeFunction = JWTClaimsSet => Option[JWTClaimsSet]

  /**
   * Returns a privileging function which verifies the expiration time.
   *
   * If a specified claims set does not have "exp" field, verification of it
   * fails; i.e., returns `None`.
   */
  def verifyNotExpired: PrivilegeFunction = claims => {
    val isValid = (until: Date) => until.toInstant.isAfter(Instant.now())

    Option(claims.getExpirationTime) filter isValid map (_ => claims) orElse None
  }

  /**
    * Implicitly converts a claim verifier function into a [[JwtClaimVerifier]].
    */
  implicit def toJwtClaimVerifier(f: PrivilegeFunction): JwtClaimVerifier =
    new JwtClaimVerifier {
      override def apply(claims: JWTClaimsSet): Option[JWTClaimsSet] = f(claims)
    }
}
