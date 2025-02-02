
//const LOCAL_EMBEDDING_MODEL= 'Xenova/all-MiniLM-L6-v2'
//const LOCAL_EMBEDDING_MODEL= 'Snowflake/snowflake-arctic-embed-s'
const LOCAL_EMBEDDING_MODEL= 'mixedbread-ai/mxbai-embed-large-v1'
export const model = process.env.model
export const embedding_local = !process.env.embedding_model || process.env.embedding_model==='local'
export const embedding_model = embedding_local?LOCAL_EMBEDDING_MODEL:process.env.embedding_model as string
export const baseUrl = process.env.baseUrl
export const repo = process.env.repo
export const OPENAI_API_KEY = process.env.OPENAI_API_KEY
export const ghToken = process.env.ghToken
export const sysPrompt = process.env.sysPrompt
export const userPrompt = process.env.userPrompt
export const pr = process.env.pr
export const includePatterns = process.env.includePatterns
export const excludePatterns = process.env.excludePatterns
export const maxLength = process.env.maxLength
export const GITHUB_LAST_COMMIT_REF = process.env.GITHUB_LAST_COMMIT_REF
export const GITHUB_PR_REF = process.env.GITHUB_PR_REF
export const GITHUB_PR_HEAD_REF=process.env.GITHUB_PR_HEAD_REF

// The head ref or source branch of the pull request in a workflow run.
//GITHUB_HEAD_REF

// The name of the base ref or target branch of the pull request in a workflow run
// GITHUB_BASE_REF
//k




// The fully-formed ref of the branch or tag that triggered the workflow run. For workflows triggered by push, this is the branch or tag ref that was pushed. For workflows triggered by pull_request, this is the pull request merge branch.
// GITHUB_REF


// The commit SHA that triggered the workflow. 
// GITHUB_SHA


// # Commonly used exit codes
const ECODE = {
  SUCCESS: 0,
  OUTDATED: 1,
  AUTH_FAILED: 2,
  SERVER_ERROR: 3,
  MISSING_BINARY: 5,
  INVALID_PARAMETER: 6,
  MISSING_DEPENDENCY: 7,
  CONDITION_NOT_SATISFIED: 8,
}

const DEFAULT_OPTIONS = {
  MODEL: 'deepseek-chat',
  BASE_URL: 'https://api.deepseek.com',
  USER_PROMPT: 'Please review the following code changes:',
  SYS_PROMPT: 'You are a professional code review assistant responsible for analyzing code changes in GitHub Pull Requests. Identify potential issues such as code style violations, logical errors, security vulnerabilities, and provide improvement suggestions. Clearly list the problems and recommendations in a concise manner.',
}

// # If the PR title or body contains any of these keywords, skip the review
const IGNORE_REVIEW_KEYWORDS = ['skip review', 'skip cr']
