/// <reference types="vite/client" />

declare module '*?worker' {
  const Ctor: new () => Worker;
  export default Ctor;
}
