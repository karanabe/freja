// @ts-check
import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import starlight from '@astrojs/starlight';
import rehypeKatex from 'rehype-katex';
import remarkMath from 'remark-math';
import rehypeMermaid from './src/plugins/rehype-mermaid.mjs';

const project = {
	title: 'Freja',
	description: 'Operate and extend the local-first, explainable L4/L7 inspection proxy.',
	repository: 'https://github.com/karanabe/freja',
};

// https://astro.build/config
export default defineConfig({
	markdown: {
		processor: unified({
			remarkPlugins: [remarkMath],
			rehypePlugins: [rehypeKatex, rehypeMermaid],
		}),
	},
	integrations: [
		starlight({
			title: {
				en: project.title,
				ja: 'Freja',
			},
			description: project.description,
			logo: {
				src: './src/assets/FrejaLogo.png',
				alt: '',
				replacesTitle: true,
			},
			favicon: '/favicon.png',
			locales: {
				root: { label: 'English', lang: 'en' },
				ja: { label: '日本語', lang: 'ja' },
			},
			social: [{ icon: 'github', label: 'GitHub', href: project.repository }],
			editLink: {
				baseUrl: `${project.repository}/edit/master/`,
			},
			customCss: [
				'katex/dist/katex.min.css',
				'./src/styles/theme.css',
				'./src/styles/site.css',
			],
			components: {
				Head: './src/components/MetadataHead.astro',
				Header: './src/components/SiteHeader.astro',
				SiteTitle: './src/components/SiteNavigation.astro',
				Sidebar: './src/components/SiteSidebar.astro',
				PageTitle: './src/components/PageTitle.astro',
			},
			expressiveCode: {
				// Slack Ochin is the light theme; Tokyo Night is the dark theme.
				themes: ['slack-ochin', 'tokyo-night'],
				useStarlightUiThemeColors: true,
				styleOverrides: { borderRadius: '0.75rem' },
			},
			lastUpdated: false,
			tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 4 },
			sidebar: [
				{
					label: 'Guides',
					translations: { ja: 'ガイド' },
					items: [{ autogenerate: { directory: 'guides' } }],
				},
				{
					label: 'Use cases',
					translations: { ja: 'ユースケース' },
					items: [
						{ slug: 'use-cases' },
						{
							label: 'HTTP/1.1 browser form lab',
							translations: { ja: 'HTTP/1.1 browserフォームlab' },
							items: [{ autogenerate: { directory: 'use-cases/browser-form-lab' } }],
						},
					],
				},
				{
					label: 'Reference',
					translations: { ja: 'リファレンス' },
					items: [{ autogenerate: { directory: 'reference' } }],
				},
				{
					label: 'Troubleshooting',
					translations: { ja: 'トラブルシューティング' },
					items: [{ autogenerate: { directory: 'troubleshooting' } }],
				},
				{
					label: 'Developer documentation',
					translations: { ja: '開発者向け' },
					items: [{ autogenerate: { directory: 'developer', collapsed: true } }],
				},
			],
		}),
	],
});
