"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="deployments"
      title="Deployments"
      subtitle="Replica health per Deployment, read straight from the cluster"
      namespaced={true}
      columns={[
        { id: "name", label: "Deployment", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "ready", label: "Ready", align: "right" },
        { id: "upToDate", label: "Up-to-date", align: "right" },
        { id: "available", label: "Available", align: "right" },
        { id: "image", label: "Image", mono: true, truncate: true },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
