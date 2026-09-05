import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PacketSentry — capture triage, made legible",
  description: "AI-assisted network capture triage using a prototype behavioral model."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
