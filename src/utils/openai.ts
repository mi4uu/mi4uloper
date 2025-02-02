import { OpenAI } from 'openai';
import { zodResponseFormat } from "openai/helpers/zod";
import { z } from "zod";
import {prompts} from './prompts/prompts'




const ReviewSchema = z.object({
  review:z.union([z.object({
    is_comment_needed: z.literal(true),
    is_action_required:z.boolean().describe("should we address this issue?"),
    category: z.enum(["bug", "idea", "critical-bug","might cause problem", "optimalization","fix","consistency","style"]),
    comment: z.string().describe("your code comment."),


  }), z.object({
    is_comment_needed:z.literal(false).describe('this change is fine and dont need your feedback.')
  })]).default({is_comment_needed:false}),


  code_improvement:z.enum(['-5','4','3','2','1','0','1','2','3','4','5']).default('0').describe("in scale from -5 to 5 code improvement after this change. -5 mean bad change, 5 mean great change")
})



const codeBlockSeparator='```'
const system_prompt=prompts.tsdev

export const reviewChanges = async (diff:string,baseURL:string,apiKey:string,modelName: string, prompt=system_prompt,extraInfo?:string) => {
  const openai = new OpenAI({ apiKey,  baseURL});
    const formatedDiff=["",codeBlockSeparator,"",diff,"",codeBlockSeparator].join("\n")
    // console.log('system:',[prompt,extraInfo||""].join('\n') )
    const response = await openai.beta.chat.completions.parse({
      model: modelName,
      messages: [
        { role: 'system', content:[prompt,extraInfo||""].join('\n') },
        { role: 'user', content: `Review the following changes: ${formatedDiff}` },
      ],
      // max_completion_tokens: 128,
      response_format: zodResponseFormat(ReviewSchema, "review"),
      temperature:0, 

    },{
      stream:false, maxRetries:5
    });

    return response.choices[0].message.parsed;

  // return response;
};