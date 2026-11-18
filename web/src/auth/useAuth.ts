import { useContext } from "react";
import { AuthContext, type AuthValue } from "./context";

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error("the console is rendered outside of its auth provider");
  }
  return value;
}
