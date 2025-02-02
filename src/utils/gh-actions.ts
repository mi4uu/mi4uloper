import { Octokit } from "octokit";
import * as config from '../config'
import { ShellError } from "bun";



// const octokit = new Octokit({ auth: config.ghToken });

// Compare: https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
// const {
//   data: { login },
// } = await octokit.rest.users.getAuthenticated();

export const getChangedFiles = async (baseRef: string, headRef: string) => {
  console.log(await Bun.$`pwd `.text())
  console.log(await Bun.$`ls `.text())


  const files = await Bun.$`git diff --name-only ${baseRef} ${headRef} `.text()
  try{
  return files.split("\n").map(f => f.trim()).filter(f => f.length > 1)
} catch (err:any ) {
  console.log(`Failed with code ${err.exitCode}`);
  console.log(err.stdout.toString());
  console.log(err.stderr.toString());
  throw err
}
}
export const getChangedSummary = async (baseRef: string, headRef: string) => {
  const files = await Bun.$`git diff  --name-status ${baseRef} ${headRef} `.text()
  return files.split("\n").map(f => f.trim()).join('\n')
}

export const getFileDiff = async (baseRef: string, headRef: string, file?: string) => {
  try{
  if (file)
    return await Bun.$`git diff  ${baseRef} ${headRef} -- ${file}`.text()
  return await Bun.$`git diff  ${baseRef} ${headRef}`.text()
} catch (err:any ) {
  console.log(`Failed with code ${err.exitCode}`);
  console.log(err.stdout.toString());
  console.log(err.stderr.toString());
  throw err
}
}

export const isGitRepo = async () => {
  const result = await Bun.$`git rev-parse --is-inside-work-tree`.text()
  return result.trim() === 'true'
}

// git diff  ${baseRef} ${headRef} -- ${file} 
// git diff --name-only ${base} ${head} 
export const addComment = async (comment: string, file: string, commit: string) => {

  return await Bun.$`gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/OWNER/REPO/pulls/PULL_NUMBER/comments \
   -f "body=${comment}" -f "commit_id=${commit}" -f "path=${file}"`.text()
}
export const getPrInfo = async () => {
  const result = await Bun.$`gh pr view ${config.pr} --repo ${config.repo} --json title,body,baseRefOid,headRefOid,headRepository,state
`.json() as {
    baseRefOid: string
    body: string
    headRefOid: string
    headRepository: {
      id: string,
      name: string
    },
    state: string
    title: string

  }
  return result
}
