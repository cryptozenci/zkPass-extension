/**
 * request template info from the blockchain
 * @param {*} templateId 
 */
export const getTemplate = (templateId) => {
  return {
    url: "",
    conditions: [],
    nodes: [{
      ip: "",
      port: "",
    }]
  }
}