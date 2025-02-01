
export const generateEmbeddings = async (chunks: string[], useLocal: boolean): Promise<number[][]> => {
  if (useLocal) {
    const db = new VectorDB();
    return chunks.map(chunk => db.embed(chunk));
  } else {
    const embeddings = new OpenAIEmbeddings({ apiKey: process.env.OPENAI_API_KEY });
    return Promise.all(chunks.map(chunk => embeddings.embed(chunk)));
  }
};

export const splitIntoChunks = (text: string, maxLength: number): string[] => {
  const chunks: string[] = [];
  for (let i = 0; i < text.length; i += maxLength) {
    chunks.push(text.slice(i, i + maxLength));
  }
  return chunks;
};