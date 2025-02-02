import OpenAI from "openai";
import * as config from '../config'
import { env } from '@xenova/transformers';
import path from 'node:path'
// env.allowRemoteModels = false;
env.localModelPath = path.join(import.meta.path,'..','..','models')
console.log( path.join(import.meta.path,'..','models'))

console.log( path.join(import.meta.path,'..'))
console.log( path.join(import.meta.path,'..','..'))




import { SentenceTransformer } from "./sentence-transformer";


export const embeddings_local = async (input:string ):Promise<number[][]>=> {
    const model = await SentenceTransformer.from_pretrained(
       config.embedding_model
   ,  {local_files_only:false} );
      const sentence_embedding = await model.encode(["Hello world!"]);
      return sentence_embedding
}
export const embeddings_local_back = async (input:string ):Promise<number[]>=> {
    const { pipeline } = await import("@xenova/transformers");

    let pipe = await pipeline("feature-extraction", config.embedding_model);
    const embedding = await pipe(input.split("\n"), { pooling: "mean", normalize: true });
    return Array.from(embedding.data);
    // return embedding.tolist()
}



export async function embeddings_remote(input:string ) {
    if (!input || typeof input !== "string") throw new Error("input must be a string");


    if (!config.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY environment variable is required");
    const openai = new OpenAI({ apiKey: config.OPENAI_API_KEY, baseURL:process.env.baseUrl });

 

    const response = await openai.embeddings.create({ input, model:config.embedding_model});
    if (!response) throw new Error('No response from OpenAI API');
    if (!response.data) throw new Error('No data in response from OpenAI API');
    if (!response.data) throw new Error('No internal data in response from OpenAI API');
    if (response.data.length !== 1) throw new Error('Expected 1 embedding, got ' + response.data.length);
    if (!response.data[0].embedding) throw new Error('No embedding in response from OpenAI API');

    return response.data[0].embedding;
}

export const  embeddings = async (input:string)=>{

    const env_model=process.env.embedding_model
    if(config.embedding_local){
        return await embeddings_local(input)
        } 
    return await embeddings_remote(input)
}