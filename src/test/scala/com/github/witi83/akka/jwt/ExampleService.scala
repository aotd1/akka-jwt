package com.github.witi83.akka.jwt

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.stream.ActorMaterializer
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet

import scala.concurrent.duration.DurationInt
import scala.io.StdIn

trait ExampleService {

  import JwtClaimBuilder._
  import JwtClaimVerifier._
  import JwtDirectives._
  import akka.http.scaladsl.server.Directives._

  import scala.concurrent.ExecutionContext.Implicits.global

  def authenticate: Authenticator[String] = barr => Some("John Snow")

  val signature = JwtSignature(JWSAlgorithm.HS256, "asdfas fjhasdf haskdflhasd fhalskdfh askldfjh lsakdjhsdhklflaskhf")

  import signature._

  implicit val claimBuilder: String => Option[JWTClaimsSet] = claimSubject[String](identity) &&
    claimIssuer("akka-jwt") &&
    claimExpiration(1.minutes)

  val route = path("authenticate") {
    authenticateBasic("secure site", jwtAuthenticator(authenticate)) { user =>
      complete(user.serialize())
    }
  } ~
  path("verify") {
    authorizeToken(verifyNotExpired) { name =>
      complete(s"You know nothing, ${name.getSubject}!")
    }
  }
}

object Main extends ExampleService {
  protected implicit val system = ActorSystem()
  protected implicit val mat = ActorMaterializer()

  def main(args: Array[String]): Unit = {
    Http().bindAndHandle(route, "0.0.0.0", 9090)

    StdIn.readLine()

    system.shutdown()
  }

}