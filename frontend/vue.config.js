const { defineConfig } = require('@vue/cli-service');
const path = require('path');

module.exports = defineConfig({
  transpileDependencies: true,
  productionSourceMap: false,  // Prodüksiyon kaynak haritalarını devre dışı bırakmak
  chainWebpack: (config) => {
    // Alias eklemeyi unutmayın
    config.resolve.alias.set('@', path.resolve(__dirname, 'src'));
  }
});