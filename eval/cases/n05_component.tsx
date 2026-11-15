import React from "react";

export function Greeting({ name }: { name: string }) {
  return <p className="greeting">Hello, {name}!</p>;
}
