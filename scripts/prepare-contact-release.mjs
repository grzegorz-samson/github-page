import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const [builtRoot, publicRoot] = process.argv.slice(2);
if (!builtRoot || !publicRoot) throw new Error('Usage: node prepare-contact-release.mjs <dist> <public-checkout>');
const rootPattern = /<div class="text-panel contact-form"[^>]*>[\s\S]*?<\/form>\s*<\/div>/g;
const oldPattern = /<div class="text-panel contact-form"[^>]*>[\s\S]*?<\/form>\s*<\/div>\s*<script type="module">[\s\S]*?<\/script>/g;
const manifest = [];
let bundlePath;
for (const lang of ['en', 'pl']) {
  const relative = `${lang}/bio/index.html`;
  const built = fs.readFileSync(path.join(builtRoot, relative), 'utf8');
  const current = fs.readFileSync(path.join(publicRoot, relative), 'utf8');
  const roots = [...built.matchAll(rootPattern)];
  const oldForms = [...current.matchAll(oldPattern)];
  const moduleTags = built.match(/<script type="module" src="\/_astro\/ContactForm[^"<>]+\.js"><\/script>/g);
  const captchaTags = built.match(/<script src="https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js" async defer><\/script>/g);
  if (roots.length !== 1 || oldForms.length !== 1 || moduleTags?.length !== 1 || captchaTags?.length !== 1) {
    throw new Error(`Unexpected contact markup in ${relative}; refusing broad replacement`);
  }
  const newBundlePath = moduleTags[0].match(/src="\/([^"<>]+)"/)[1];
  if (bundlePath && bundlePath !== newBundlePath) throw new Error('Language bundles differ');
  bundlePath = newBundlePath;
  const replacement = `${roots[0][0]} ${captchaTags[0]} ${moduleTags[0]}`;
  const updated = current.replace(oldPattern, () => replacement);
  // Everything outside the contact form must remain byte-for-byte identical.
  if (current.replace(oldPattern, '__CONTACT__') !== updated.replace(replacement, '__CONTACT__')) {
    throw new Error(`Unrelated page changes in ${relative}`);
  }
  if (!updated.includes('data-action="contact"') || !updated.includes('data-site-key="0x4AAAAAAFXpcHNBkQZECI0E"')) {
    throw new Error(`Missing production CAPTCHA configuration in ${relative}`);
  }
  fs.writeFileSync(path.join(publicRoot, relative), updated);
  manifest.push(relative);
}
const bundle = fs.readFileSync(path.join(builtRoot, bundlePath), 'utf8');
if (/\bimport\s|\bimport\(/.test(bundle)) throw new Error('Contact bundle has unexpected dependencies');
fs.copyFileSync(path.join(builtRoot, bundlePath), path.join(publicRoot, bundlePath));
manifest.push(bundlePath);
for (const file of manifest) {
  const contents = fs.readFileSync(path.join(publicRoot, file));
  const text = contents.toString('utf8');
  if (/\bre_[A-Za-z0-9_-]{20,}\b|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|oauth_token\s*=|RESEND_API_KEY|TURNSTILE_SECRET_KEY|ADMIN_API_TOKEN/.test(text)) {
    throw new Error(`Potential private credential in ${file}`);
  }
  console.log(JSON.stringify({ file, bytes: contents.length, sha256: crypto.createHash('sha256').update(contents).digest('hex') }));
}
