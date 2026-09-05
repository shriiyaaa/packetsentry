/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    if (process.env.NODE_ENV === "development") {
      const apiPort = process.env.PACKET_SENTRY_API_PORT ?? "8000";
      return [{ source: "/api/:path*", destination: `http://127.0.0.1:${apiPort}/api/:path*` }];
    }
    return [];
  }
};

export default nextConfig;
