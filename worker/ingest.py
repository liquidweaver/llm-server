from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.vector_stores.qdrant import QdrantVectorStore
from llama_index.core.node_parser import SentenceSplitter

reader = SimpleDirectoryReader("/data", recursive=True, file_extractor="auto")
documents = reader.load_data()
parser = SentenceSplitter(chunk_size=512, chunk_overlap=64)
nodes = parser.get_nodes_from_documents(documents)

store = QdrantVectorStore(url="http://qdrant:6333", collection_name="kb")
index = VectorStoreIndex.from_nodes(nodes, vector_store=store, embed_model="local: bge-small-en")
index.storage_context.persist()
