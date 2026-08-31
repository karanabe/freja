import { readdir } from 'node:fs/promises';
import path from 'node:path';

const contentRoot = path.resolve(import.meta.dirname, '../src/content/docs');
const japaneseRoot = path.join(contentRoot, 'ja');

async function contentPaths(root, ignoredDirectory) {
	const paths = [];

	async function visit(directory) {
		for (const entry of await readdir(directory, { withFileTypes: true })) {
			if (entry.isDirectory() && entry.name === ignoredDirectory) {
				continue;
			}

			const entryPath = path.join(directory, entry.name);
			if (entry.isDirectory()) {
				await visit(entryPath);
			} else if (/\.mdx?$/.test(entry.name)) {
				paths.push(path.relative(root, entryPath).split(path.sep).join('/'));
			}
		}
	}

	await visit(root);
	return paths.sort();
}

const englishPaths = await contentPaths(contentRoot, 'ja');
const japanesePaths = await contentPaths(japaneseRoot);
const englishOnly = englishPaths.filter((entry) => !japanesePaths.includes(entry));
const japaneseOnly = japanesePaths.filter((entry) => !englishPaths.includes(entry));

if (englishOnly.length > 0 || japaneseOnly.length > 0) {
	if (englishOnly.length > 0) {
		console.error(`Missing Japanese pages:\n${englishOnly.map((entry) => `  ${entry}`).join('\n')}`);
	}
	if (japaneseOnly.length > 0) {
		console.error(`Missing English pages:\n${japaneseOnly.map((entry) => `  ${entry}`).join('\n')}`);
	}
	process.exitCode = 1;
} else {
	console.log(`Validated ${englishPaths.length} matching English/Japanese content routes.`);
}
