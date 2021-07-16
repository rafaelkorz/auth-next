import { AuthContext } from './../contexts/AuthContext';
import { useContext } from 'react';
import { ValidateUserPermissions } from '../utils/validateUserPermissions';
type UseCanParams = {
  permissions?: string[],
  roles?: string[]
}

export function useCan({ permissions, roles}: UseCanParams) {
  const { user, isAuthenticated } = useContext(AuthContext)

  if (!isAuthenticated) {
    return false;
  }

  const userHasaValidPermissions = ValidateUserPermissions({
    user,
    permissions,
    roles
  })


  return userHasaValidPermissions;
}
