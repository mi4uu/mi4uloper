import { Octokit } from "octokit";
import * as config from '../config'



const octokit = new Octokit({ auth: config.ghToken });

// Compare: https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
const {
  data: { login },
} = await octokit.rest.users.getAuthenticated();

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