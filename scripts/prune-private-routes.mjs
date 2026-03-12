import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const shouldPrunePrivateCv = process.env.EXCLUDE_PRIVATE_CV === 'true';

if (!shouldPrunePrivateCv) {
  process.exit(0);
}

const distDir = join(process.cwd(), 'dist');
const privateRoutes = [
  join(distDir, 'pl', 'cv-qa'),
  join(distDir, 'en', 'cv-qa')
];

for (const routeDir of privateRoutes) {
  if (existsSync(routeDir)) {
    rmSync(routeDir, { recursive: true, force: true });
  }
}
