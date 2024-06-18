import { Request, Response, NextFunction } from "express";
import { Request } from "express-serve-static-core";

declare module "express-serve-static-core" {
  interface Request {
    csrfToken: () => string;
  }
}

declare module "tiny-csrf" {
  type ForbiddenMethods = Array<
    "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD"
  >;
  type ExcludedUrls = Array<string | RegExp>;
  type ExcludedReferers = Array<string>;

  interface CsurfOptions {
    secret: string;
    forbiddenMethods?: ForbiddenMethods;
    excludedUrls?: ExcludedUrls;
    excludedReferers?: ExcludedReferers;
  }

  function csurf(
    secret: string,
    forbiddenMethods?: ForbiddenMethods,
    excludedUrls?: ExcludedUrls,
    excludedReferers?: ExcludedReferers
  ): (req: Request, res: Response, next: NextFunction) => void;

  interface Request<ParamsDictionary, any, any, ParsedQs, Record> {
    csrfToken(): string;
  }
  export = csurf;
}
