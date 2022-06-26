package sn.meum.securityservice.security;

public class JwtUtils {
    public static final String SECRET="mySecret123";
    public static final String AUTH_HEADER="Authorization";
    public static final long EXPIRE_ACCESS_TOKEN=5*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 15*60*1000;
    public static final String PREFIX="Bearer ";
}
