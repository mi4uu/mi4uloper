import { Octokit } from '@octokit/rest';

export const getDiff = async (baseUrl: string): Promise<string> => {
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
  const [owner, repo] = new URL(baseUrl).pathname.split('/').slice(1, 3);
  const prNumber = new URL(baseUrl).pathname.split('/').pop();

  const { data } = await octokit.rest.pulls.get({
    owner,
    repo,
    pull_number: parseInt(prNumber!),
    mediaType: { format: 'diff' },
  });

  return data as unknown as string;
};