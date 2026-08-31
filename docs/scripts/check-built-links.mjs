import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

const outputRoot = path.resolve(import.meta.dirname, '../dist');

async function filesBelow(directory) {
	const files = [];
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		const entryPath = path.join(directory, entry.name);
		if (entry.isDirectory()) {
			files.push(...(await filesBelow(entryPath)));
		} else {
			files.push(entryPath);
		}
	}
	return files;
}

function outputPath(pathname) {
	const relativePath = decodeURIComponent(pathname).replace(/^\/+/, '');
	const directPath = path.join(outputRoot, relativePath);
	return path.extname(relativePath) ? directPath : path.join(directPath, 'index.html');
}

async function exists(filePath) {
	try {
		return (await stat(filePath)).isFile();
	} catch (error) {
		if (error && typeof error === 'object' && error.code === 'ENOENT') {
			return false;
		}
		throw error;
	}
}

const htmlFiles = (await filesBelow(outputRoot)).filter((file) => file.endsWith('.html'));
const htmlByPath = new Map();
const idsByPath = new Map();

for (const file of htmlFiles) {
	const html = await readFile(file, 'utf8');
	htmlByPath.set(file, html);
	idsByPath.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1])));
}

const failures = [];
for (const [file, html] of htmlByPath) {
	const route = `/${path.relative(outputRoot, file).split(path.sep).join('/').replace(/index\.html$/, '')}`;

	for (const match of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
		const reference = match[1].replaceAll('&amp;', '&');
		if (/^(?:https?:|\/\/|mailto:|tel:|javascript:|data:)/.test(reference)) {
			continue;
		}

		const url = new URL(reference, `https://freja.invalid${route}`);
		const target = outputPath(url.pathname);
		if (!(await exists(target))) {
			failures.push(`${path.relative(outputRoot, file)}: missing ${reference}`);
			continue;
		}

		if (url.hash && target.endsWith('.html')) {
			const id = decodeURIComponent(url.hash.slice(1));
			if (id && !idsByPath.get(target)?.has(id)) {
				failures.push(`${path.relative(outputRoot, file)}: missing anchor ${reference}`);
			}
		}
	}
}

if (failures.length > 0) {
	console.error(failures.join('\n'));
	process.exitCode = 1;
} else {
	console.log(`Validated ${htmlFiles.length} generated HTML files and their internal links and anchors.`);
}
