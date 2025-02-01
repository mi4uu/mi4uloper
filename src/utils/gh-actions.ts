import { Octokit } from "octokit";
import * as config from '../config'



const octokit = new Octokit({ auth: config.ghToken });

// Compare: https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
const {
  data: { login },
} = await octokit.rest.users.getAuthenticated();

export const getChangedFiles = async (baseRef:string, headRef:string)=>{
   return await Bun.$`git diff --name-only ${baseRef} ${headRef} `.text()
}

export const getChanged = async (baseRef:string, headRef:string, file?:string)=>{
    if(file)
   return await Bun.$`git diff  ${baseRef} ${headRef} -- ${file}`.text()
    return await Bun.$`git diff  ${baseRef} ${headRef}`.text()
}

export const isGitRepo = async ()=>{
   const result = await Bun.$`git rev-parse --is-inside-work-tree`.text()
   return result.trim() === 'true'
}

// git diff  ${baseRef} ${headRef} -- ${file} 
// git diff --name-only ${base} ${head} 

export const getPrInfo = async ()=>{
    const result = await Bun.$`gh pr view ${config.pr} --repo ${config.repo} --json title,body,baseRefOid,headRefOid,headRepository,state
`.json() as {
    baseRefOid: string
  body: string
  headRefOid: string
  headRepository: {
    id:string,
    name:string
  },
  state: string
  title: string

}
return result
}

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