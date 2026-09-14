"use client";

import ResourceBrowser from "@/app/components/k8s/ResourceBrowser";

export default function Page() {
  return (
    <ResourceBrowser
      kind="ingresses"
      title="Ingresses"
      subtitle="Hosts, TLS and backends for every Ingress, plus whether the controller has assigned an address"
      columns={[
        { id: "name", label: "Ingress", mono: true, truncate: true },
        { id: "namespace", label: "Namespace" },
        { id: "hosts", label: "Hosts", mono: true, truncate: true },
        { id: "class", label: "Class" },
        { id: "tls", label: "TLS" },
        { id: "backends", label: "Backends", mono: true, truncate: true },
        { id: "address", label: "Address", mono: true, truncate: true },
        { id: "age", label: "Age", align: "right" },
      ]}
    />
  );
}
