import { Octokit } from "octokit";
import * as config from '../config'



// const octokit = new Octokit({ auth: config.ghToken });

// Compare: https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
// const {
//   data: { login },
// } = await octokit.rest.users.getAuthenticated();

export const getChangedFiles = async (baseRef: string, headRef: string) => {
  console.log(await Bun.$`pwd `.text())
  console.log(await Bun.$`ls `.text())


  const files = await Bun.$`git diff --name-only ${baseRef} ${headRef} `.text()
  return files.split("\n").map(f => f.trim()).filter(f => f.length > 1)
}
export const getChangedSummary = async (baseRef: string, headRef: string) => {
  const files = await Bun.$`git diff  --name-status ${baseRef} ${headRef} `.text()
  return files.split("\n").map(f => f.trim()).join('\n')
}

export const getFileDiff = async (baseRef: string, headRef: string, file?: string) => {
  if (file)
    return await Bun.$`git diff  ${baseRef} ${headRef} -- ${file}`.text()
  return await Bun.$`git diff  ${baseRef} ${headRef}`.text()
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
