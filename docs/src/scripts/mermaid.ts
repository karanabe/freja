const diagramSelector = 'pre.mermaid';
const diagramSources = new WeakMap<HTMLElement, string>();
let renderQueue = Promise.resolve();

function readThemeColors() {
	const probe = document.createElement('span');
	const canvasContext = document.createElement('canvas').getContext('2d');
	probe.style.cssText = 'position:fixed;visibility:hidden;pointer-events:none';
	document.documentElement.append(probe);

	const readColor = (property: string) => {
		probe.style.color = `var(${property})`;
		const computedColor = getComputedStyle(probe).color;

		if (!canvasContext) return computedColor;
		canvasContext.fillStyle = '#000000';
		canvasContext.fillStyle = computedColor;
		return canvasContext.fillStyle;
	};

	const colors = {
		accent: readColor('--sl-color-accent'),
		accentHigh: readColor('--sl-color-accent-high'),
		accentLow: readColor('--sl-color-accent-low'),
		background: readColor('--sl-color-black'),
		gray2: readColor('--sl-color-gray-2'),
		gray3: readColor('--sl-color-gray-3'),
		gray4: readColor('--sl-color-gray-4'),
		gray5: readColor('--sl-color-gray-5'),
		gray6: readColor('--sl-color-gray-6'),
		text: readColor('--sl-color-white'),
	};

	probe.remove();
	return colors;
}

function getMermaidConfig() {
	const colors = readThemeColors();
	const rootStyles = getComputedStyle(document.documentElement);

	return {
		startOnLoad: false,
		securityLevel: 'strict' as const,
		suppressErrorRendering: true,
		look: 'neo' as const,
		theme: 'base' as const,
		fontFamily: rootStyles.getPropertyValue('--sl-font').trim(),
		flowchart: {
			curve: 'rounded' as const,
			nodeSpacing: 42,
			rankSpacing: 54,
		},
		sequence: {
			actorMargin: 64,
			messageMargin: 42,
		},
		themeVariables: {
			darkMode: document.documentElement.dataset.theme !== 'light',
			background: colors.background,
			primaryColor: colors.accentLow,
			primaryTextColor: colors.accentHigh,
			primaryBorderColor: colors.accent,
			secondaryColor: colors.gray6,
			secondaryTextColor: colors.text,
			secondaryBorderColor: colors.gray4,
			tertiaryColor: colors.gray5,
			tertiaryTextColor: colors.text,
			tertiaryBorderColor: colors.gray3,
			lineColor: colors.gray3,
			textColor: colors.gray2,
			mainBkg: colors.accentLow,
			nodeBorder: colors.accent,
			clusterBkg: colors.gray6,
			clusterBorder: colors.gray4,
			edgeLabelBackground: colors.background,
			titleColor: colors.text,
			archEdgeColor: colors.gray3,
			archEdgeArrowColor: colors.gray3,
			archGroupBorderColor: colors.gray4,
			noteBkgColor: colors.accentLow,
			noteTextColor: colors.text,
			noteBorderColor: colors.accent,
			actorBkg: colors.gray6,
			actorTextColor: colors.text,
			actorBorder: colors.gray4,
			actorLineColor: colors.gray4,
			signalColor: colors.gray2,
			signalTextColor: colors.gray2,
			labelBoxBkgColor: colors.gray6,
			labelBoxBorderColor: colors.gray4,
			labelTextColor: colors.text,
			loopTextColor: colors.text,
			activationBkgColor: colors.accentLow,
			activationBorderColor: colors.accent,
		},
	};
}

async function renderDiagrams() {
	const diagrams = Array.from(document.querySelectorAll<HTMLElement>(diagramSelector));
	if (diagrams.length === 0) return;

	const { default: mermaid } = await import('mermaid');
	mermaid.initialize(getMermaidConfig());

	for (const diagram of diagrams) {
		const source = diagramSources.get(diagram) ?? diagram.textContent?.trim() ?? '';
		diagramSources.set(diagram, source);
		diagram.replaceChildren(document.createTextNode(source));
		diagram.removeAttribute('data-processed');
		diagram.classList.remove('mermaid-error');
		diagram.setAttribute('aria-busy', 'true');

		try {
			await mermaid.run({ nodes: [diagram] });
		} catch (error) {
			diagram.replaceChildren(document.createTextNode(source));
			diagram.removeAttribute('data-processed');
			diagram.classList.add('mermaid-error');
			console.error('Unable to render Mermaid diagram.', error);
		} finally {
			diagram.removeAttribute('aria-busy');
		}
	}
}

function queueDiagramRender() {
	renderQueue = renderQueue.catch(() => undefined).then(renderDiagrams);
}

new MutationObserver((records) => {
	if (records.some((record) => record.attributeName === 'data-theme')) {
		queueDiagramRender();
	}
}).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

queueDiagramRender();
