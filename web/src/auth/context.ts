import { createContext } from "react";
import type { SessionUser } from "./session";

export interface AuthValue {
  user: SessionUser | null;
  isAdmin: boolean;
  ready: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

export const AuthContext = createContext<AuthValue | null>(null);
