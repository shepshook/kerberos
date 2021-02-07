# Kerberos
A network consisting of Client, Server and KDC (Key Distribution Server) using DES encryption algo

Client is a simple Console application that uses Kerberos.Lib classes to authenticate on KDC and then on the Server itself.

Both Server and KDC are ASP.NET Core apps.

You can run the whole network using single command (Docker is required)

```
docker-compose up
```

This will build all the applications in Docker containers and run them in a network.
