import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
	docs: defineCollection({
		loader: docsLoader(),
		schema: docsSchema({
			extend: z.object({
				publishedAt: z.coerce.date().optional(),
				updatedAt: z.coerce.date().optional(),
				tags: z
					.array(z.string().trim().min(1))
					.refine((values) => new Set(values).size === values.length, {
						message: 'Tags must be unique within a page.',
					})
					.default([]),
			}),
		}),
	}),
};
