name := "akka-jwt"
organization := "com.github.witi83"
version := "1.3.0"
scalaVersion := "2.11.8"

scalacOptions := Seq("-deprecation",
                     "-encoding", "utf8",
                     "-feature",
                     "-target:jvm-1.8",
                     "-unchecked",
                     "-Yinline-warnings",
                     "-Yno-adapted-args",
                     "-Ywarn-dead-code",
                     "-Ywarn-numeric-widen",
                     "-Ywarn-value-discard",
                     "-Xfatal-warnings",
                     "-Xfuture")

libraryDependencies ++= {
  val akkaHttpVersion = "10.0.1"
  Seq(
    "com.typesafe.akka" %% "akka-http"          % akkaHttpVersion,
    "com.nimbusds"      %  "nimbus-jose-jwt"    % "4.33",

    "org.scalatest"     %% "scalatest"          % "3.0.1" % "test",
    "com.typesafe.akka" %% "akka-http-testkit"  % akkaHttpVersion % "test"
  )
}

publishMavenStyle := true

publishArtifact in Test := false

licenses := Seq("MIT" -> url("http://opensource.org/licenses/MIT"))

homepage := Some(url("https://github.com/witi83/akka-jwt"))

pomExtra := <scm>
  <url>https://github.com/witi83/akka-jwt.git</url>
  <connection>scm:git:https://github.com/witi83/akka-jwt.git</connection>
</scm>
  <developers>
    <developer>
      <id>kikuomax</id>
      <name>Kikuo Emoto</name>
      <url>https://github.com/kikuomax</url>
    </developer>
    <developer>
      <id>witi83</id>
      <name>Witold Czaplewski</name>
      <url>https://github.com/witi83</url>
    </developer>
  </developers>

credentials += Credentials(Path.userHome / ".ivy2" / ".credentials")
