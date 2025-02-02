import * as config from './config'
import { embeddings } from './utils/embeddings'
import {  addComment, getChangedFiles, getChangedSummary, getFileDiff, getPrInfo } from './utils/gh-actions'
import { logger } from './utils/logger'
import { reviewChanges } from './utils/openai'
import {prompts} from './utils/prompts/prompts'
const codeBlockSeparator='```'

const main = async ()=>{

  const info=await getPrInfo()

  // const baseRef='2b0b546099cd0582e1cf9674ce2d4c4050a0eb2e'
  // const headRef='HEAD'
  // const baseRef=info.baseRefOid
  // const headRef=info.headRefOid

  const headRef=config.GITHUB_PR_HEAD_REF!
  const baseRef=config.GITHUB_PR_REF!

  const files=await getChangedFiles(baseRef,headRef)
  const summary=await getChangedSummary(baseRef,headRef)
  logger.log(files)
  for(const file of files){
    const diff = await getFileDiff(baseRef,headRef,file)
    // console.log(diff)
    if(diff.length>3000) continue
    logger.log(file)
    // const emb=await embeddings(diff)
    // console.log(JSON.stringify(emb))
    // console.log({
    //   diff_len:diff.length,
    //   emb_len:JSON.stringify(emb).length
    // })
    const extraInfo=[`PR title: ${info.title}`,`PR body: ${info.body}`,
    '# all files changed:','`',summary,'`','','# reviewing file:',file].join('\n')
  
    const response = await reviewChanges(diff,"https://openai.lipinski.app/v1", "x","Qwen/Qwen2.5-Coder-14B-Instruct-AWQ", prompts.revprompt ,extraInfo)
    
    logger.log(response)
    logger.log("")
    logger.log('-----------------')
    logger.log("")
    if(response?.review.is_comment_needed){
      const msg=`${response.review.comment}
      IS ACTION REQUIRED: ${response.review.is_action_required?'YES':'NO'}
      `

      logger.info("sending comment")
      const commentResult=await addComment(response.review.comment, file,baseRef)
      logger.info(`comment send: ${commentResult}`)
    }
  }

}

await main()