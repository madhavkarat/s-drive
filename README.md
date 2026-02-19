# 📁 S-DRIVE

A Google Photos-inspired document & image archive website for transparency and public accountability.

## Features

- **📸 Bulk Image Upload** — Drag & drop or browse to upload multiple images at once
- **🔍 Search** — Search by tags, descriptions, or file names
- **⭐ Star** — Mark important photos for quick access
- **📁 Albums** — Organize photos into named albums
- **🖼️ Lightbox Viewer** — Full-screen image viewer with keyboard navigation
- **🗑️ Trash** — Soft-delete with recovery
- **💾 Local Storage** — All data stored in your browser (no server needed)
- **📱 Responsive** — Works on desktop, tablet, and mobile
- **🌙 Dark Theme** — Easy on the eyes

## Quick Start

```bash
# Clone the repo
git clone https://github.com/yourusername/d-drive.git
cd d-drive

# Open in browser (no build step needed!)
open index.html
# or use a local server:
npx serve .
```

## Deployment

Deploy instantly to any static host:

- **Vercel**: `vercel deploy`
- **Netlify**: Drag & drop the folder
- **GitHub Pages**: Push to `main` and enable Pages
- **Cloudflare Pages**: Connect your repo

## Tech Stack

- Pure HTML, CSS, JavaScript (no frameworks, no dependencies)
- localStorage for persistence
- Google Material Icons

## Security Notes

- For production use, add Cloudflare for DDoS protection
- Use WHOIS privacy on your domain
- Consider adding a SecureDrop link for anonymous tips
- Always verify and redact sensitive content before publishing
