import { OpenAI } from 'openai';
import * as config from '../config'
export const reviewChanges = async (embeddings: number[][], modelName: string): Promise<string[]> => {
  const openai = new OpenAI({ apiKey:config.OPENAI_API_KEY,  baseURL:config.baseUrl });
  const comments: string[] = [];

  for (const embedding of embeddings) {
    const response = await openai.chat.completions.create({
      model: modelName,
      messages: [
        { role: 'system', content: 'You are a code reviewer. Provide constructive feedback on the changes.' },
        { role: 'user', content: `Review the following changes: ${JSON.stringify(embedding)}` },
      ],
    });
    comments.push(response.choices[0].message.content!);
  }

  return comments;
};