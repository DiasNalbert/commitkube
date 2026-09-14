"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="services"
      title="Services"
      subtitle="Cluster addressing for each Service — the target an Ingress backend resolves to"
      columns={[
        { id: "name", label: "Service", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "type", label: "Type" },
        { id: "clusterIP", label: "Cluster IP", mono: true },
        { id: "externalIP", label: "External", mono: true, truncate: true },
        { id: "ports", label: "Ports", mono: true, truncate: true },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
