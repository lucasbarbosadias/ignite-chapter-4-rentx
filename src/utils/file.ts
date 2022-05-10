import fs from 'fs';

export const deleteFile = async (filename: string) => {
  try {
    // o .stat(nome) busca se tem um arquivo na pasta com esse nome e caso não tenha cai no catch
    await fs.promises.stat(filename);
  } catch {
    return;
  }
  // eslint-disable-next-line max-len
  // caso o stat tenha encontrado o arquivo o .unlink(nome) vai deletar o arquivo com o nome informado
  await fs.promises.unlink(filename);
};
