const favicon = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64" fill="none">
  <rect width="64" height="64" rx="16" fill="#07131F"/>
  <path d="M32 9L50 15.5V29.2C50 40.6 42.8 50.8 32 55C21.2 50.8 14 40.6 14 29.2V15.5L32 9Z" fill="#0D2433" stroke="#49E6D1" stroke-width="2.5"/>
  <path d="M32 18L41.5 21.4V29.1C41.5 35.3 37.7 41 32 44C26.3 41 22.5 35.3 22.5 29.1V21.4L32 18Z" fill="#102F41" stroke="#9CF7E9" stroke-width="2"/>
  <path d="M27 29.5H37M29 25.5H35M29 33.5H35" stroke="#49E6D1" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="48.5" cy="16" r="4.5" fill="#FFB86B" stroke="#07131F" stroke-width="2"/>
</svg>`;

export function GET() {
  return new Response(favicon, {
    headers: {
      "Cache-Control": "public, max-age=31536000, immutable",
      "Content-Type": "image/svg+xml"
    }
  });
}
