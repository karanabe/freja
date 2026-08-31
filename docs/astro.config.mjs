// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const project = {
	title: 'Freja',
	description: 'Operate and extend the local-first, explainable L4/L7 inspection proxy.',
	repository: 'https://github.com/karanabe/freja',
};

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: {
				en: project.title,
				ja: 'Freja',
			},
			description: project.description,
			locales: {
				root: { label: 'English', lang: 'en' },
				ja: { label: '日本語', lang: 'ja' },
			},
			social: [{ icon: 'github', label: 'GitHub', href: project.repository }],
			editLink: {
				baseUrl: `${project.repository}/edit/master/`,
			},
			customCss: ['./src/styles/theme.css', './src/styles/site.css'],
			components: {
				Head: './src/components/MetadataHead.astro',
				SiteTitle: './src/components/SiteNavigation.astro',
			},
			expressiveCode: {
				// Slack Ochin is the light theme; Tokyo Night is the dark theme.
				themes: ['slack-ochin', 'tokyo-night'],
				useStarlightUiThemeColors: true,
				styleOverrides: { borderRadius: '0.75rem' },
			},
			lastUpdated: false,
			sidebar: [
				{
					label: 'Guides',
					translations: { ja: 'ガイド' },
					items: [{ autogenerate: { directory: 'guides' } }],
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
