
const LOCAL_EMBEDDING_MODEL= 'Xenova/all-MiniLM-L6-v2'


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