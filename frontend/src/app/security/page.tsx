"use client";

import { useEffect } from "react";

/** The single Security dashboard became two. Anything still pointing at the old
 *  path lands on the code side, which is what it used to open on. */
export default function Page() {
  useEffect(() => { window.location.replace("/security/code"); }, []);
  return <div className="p-6 text-zinc-500">Redirecionando para Code Security…</div>;
}
