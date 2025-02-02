import { pipeline } from "@huggingface/transformers";


export const local_gen = async (input:string )=> {
    // const { pipeline } = await import("@xenova/transformers")
    // const model = 'Xenova/codegen-350M-mono'
    const generator = await pipeline(
        "text-generation",
        "onnx-community/Llama-3.2-1B-Instruct",
      );
      
      // Define the list of messages
      const messages = [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Tell me a funny joke." },
      ];
      
      // Generate a response
      const output = await generator(messages, { max_new_tokens: 128 });
    //   console.log(output[0].generated_text.at(-1).content);
      return output[0]
    // return gen
    // return Array.from(embedding.data);
    // return embedding.tolist()
}
const x=await local_gen("sss")
console.log(x)
