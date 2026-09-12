const mermaidLanguageClass = 'language-mermaid';

/**
 * Turn Mermaid code fences into containers that the client renderer can find.
 * Running before Expressive Code also keeps diagram source out of its code-block UI.
 */
export default function rehypeMermaid() {
	return (tree, file) => {
		const fallbackLabel = file.path?.includes('/ja/') ? 'Mermaid 図' : 'Mermaid diagram';
		transformChildren(tree, fallbackLabel);
	};
}

function transformChildren(parent, fallbackLabel) {
	if (!Array.isArray(parent.children)) return;

	for (let index = 0; index < parent.children.length; index += 1) {
		const node = parent.children[index];
		const source = getMermaidSource(node);

		if (source !== undefined) {
			parent.children[index] = {
				type: 'element',
				tagName: 'pre',
				properties: {
					className: ['mermaid'],
					role: 'img',
					ariaLabel: getAccessibleTitle(source) ?? fallbackLabel,
					tabIndex: 0,
				},
				children: [{ type: 'text', value: source.trim() }],
			};
			continue;
		}

		transformChildren(node, fallbackLabel);
	}
}

function getMermaidSource(node) {
	if (node?.type !== 'element' || node.tagName !== 'pre' || node.children?.length !== 1) {
		return undefined;
	}

	const code = node.children[0];
	const classes = Array.isArray(code?.properties?.className) ? code.properties.className : [];
	if (code?.type !== 'element' || code.tagName !== 'code' || !classes.includes(mermaidLanguageClass)) {
		return undefined;
	}

	return code.children?.map((child) => (child.type === 'text' ? child.value : '')).join('') ?? '';
}

function getAccessibleTitle(source) {
	const title = source.match(/^\s*accTitle\s*:\s*(.+?)\s*$/m)?.[1];
	return title?.replace(/^(['"])(.*)\1$/, '$2');
}
