// A remark step for Article: HTML comments in the Markdown (`<!-- … -->`, a note for whoever edits the file) are not
// shown. Markdown keeps a comment as an `html` node, block or inline, and react-markdown, which renders no raw HTML,
// would print it as text. Code that holds `<!--` is a `code` or `inlineCode` node, so it stays as written. Pure, so
// `node --test` loads it (src/runtime/articles.test.mjs).

type MdNode = { type: string; value?: string; children?: MdNode[] };

const isComment = (node: MdNode) => {
  const value = node.type === 'html' ? node.value?.trim() ?? '' : '';
  return value.startsWith('<!--') && value.endsWith('-->');
};

function dropComments(node: MdNode) {
  if (!node.children) return;
  node.children = node.children.filter(child => !isComment(child));
  node.children.forEach(dropComments);
}

/** The remark plugin: removes every HTML comment node from the tree. */
export function remarkDropComments() {
  return (tree: MdNode) => { dropComments(tree); };
}
