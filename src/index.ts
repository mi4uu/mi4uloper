import { getDiff } from './utils/diff';
import { generateEmbeddings, splitIntoChunks } from './utils/vectordb';
import { reviewChanges } from './utils/openai';
import { Octokit } from '@octokit/rest';

interface Params {
  base_url: string;
  model_name: string;
  max_content_length: number;
  use_local_embedding: boolean;
}

const parseParams = (): Params => {
  const args = Bun.argv.slice(2);
  const params: Params = {
    base_url: args.find(arg => arg.startsWith('--base_url='))?.split('=')[1] || '',
    model_name: args.find(arg => arg.startsWith('--model_name='))?.split('=')[1] || 'gpt-4',
    max_content_length: parseInt(args.find(arg => arg.startsWith('--max_content_length='))?.split('=')[1] || '0'),
    use_local_embedding: args.find(arg => arg.startsWith('--use_local_embedding='))?.split('=')[1] === 'true',
  };
  return params;
};

const main = async () => {
  const params = parseParams();
  const { base_url, model_name, max_content_length, use_local_embedding } = params;

  // Fetch PR diff
  const diff = await getDiff(base_url);

  // Split into chunks if max_content_length is set
  const chunks = max_content_length > 0 ? splitIntoChunks(diff, max_content_length) : [diff];

  // Generate embeddings
  const embeddings = await generateEmbeddings(chunks, use_local_embedding);

  // Review changes using OpenAI
  const reviewComments = await reviewChanges(embeddings, model_name);

  // Add comments to PR
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
  const [owner, repo] = new URL(base_url).pathname.split('/').slice(1, 3);
  const prNumber = new URL(base_url).pathname.split('/').pop();

  for (const comment of reviewComments) {
    await octokit.rest.pulls.createReviewComment({
      owner,
      repo,
      pull_number: parseInt(prNumber!),
      body: comment,
      commit_id: process.env.GITHUB_SHA,
      path: comment.path, // Assuming comment includes path
      line: comment.line, // Assuming comment includes line number
    });
  }
};

main().catch(console.error);