import { AuthTokenError } from './../services/errors/AuthTokenError';
import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from "next";
import { destroyCookie, parseCookies } from "nookies";
import decode  from 'jwt-decode';
import { ValidateUserPermissions } from './validateUserPermissions';

type withSSRAuthOptions = {
  permissions?: string[];
  roles?: string[];
}

export function withSSRAuth<P>(fn: GetServerSideProps<P>, options?: withSSRAuthOptions) {
  return async(ctx: GetServerSidePropsContext): Promise<GerServerSidePropsResult<P>> => {
    const cookies = parseCookies(ctx);
    const token = cookies['nextauth.token']

    if (!cookies['nextauth.token']) {
      return {
        redirect: {
          destination: '/',
          permanent: false,
        }
      }
    }

    if (options) {
      const user = decode<{ permissions: string[], roles: string[] }>(token);
      const { permissions, roles } = options;

      const userHasaValidPermissions = ValidateUserPermissions({
        user,
        permissions,
        roles
      })

      if (!userHasaValidPermissions) {
        return {
          redirect: {
            destination: '/dashboard',
            permanent: false,
          }
        }
      }
    }
  
  try {
    return await fn(ctx)
  } catch (err) {
    if (err instanceof AuthTokenError) {
      destroyCookie(ctx, 'nextauth.token');
      destroyCookie(ctx, 'nextauth.refreshToken');
  
      return {
        redirect: {
          destination: '/',
          permanent: false,
        }
      }
    }
  }
  
  }
}