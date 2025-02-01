import * as config from './config'
import { getChangedFiles } from './utils/gh-actions'
const main = async ()=>{
  const baseRef='2b0b546099cd0582e1cf9674ce2d4c4050a0eb2e'
  const headRef='HEAD'
  const files=await getChangedFiles(baseRef,headRef)
  console.log(files)

}

await main()