"use client";

import { useEffect } from "react";

/** Users, Groups and Access became one screen: three pages for one question
 *  was the confusion, not the answer. Old links still land somewhere. */
export default function Page() {
  useEffect(() => { window.location.replace("/iam"); }, []);
  return <div className="p-6 text-zinc-500">Redirecionando para IAM…</div>;
}
