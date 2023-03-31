import { Request } from "express";

type AllowedFields = readonly string[];

export default function filterRequestBody(
  body: Request["body"],
  allowedFields: AllowedFields
) {
  const filteredBody: Record<string, unknown> = {};

  for (const key of Object.keys(body)) {
    if (allowedFields.includes(key)) {
      filteredBody[key] = body[key];
    }
  }

  return filteredBody;
}
