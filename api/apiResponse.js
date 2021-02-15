module.exports = {
    create: function(params) {
        return {
            success: params.success,
            message: params.message,
            data: params.data
        }
    }
}