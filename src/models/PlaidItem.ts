import mongoose from 'mongoose';

// Define the schema for the account subdocument
const accountSchema = new mongoose.Schema({
    accountId: { type: String, required: true },
    name: { type: String, required: true },
    type: { type: String, required: true },
    subtype: { type: String, required: true },
    mask: { type: String, required: true },
    institutionId: { type: String, required: true },
    institutionName: { type: String, required: true },

}, { _id: false }); // prevent Mongoose from creating _id for subdocuments

const plaidItemSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    accessToken: {
        type: String,
        required: true,
    },
    itemId: {
        type: String,
        required: true,
    },
    institutionId: {
        type: String,
        required: true,
    },
    institutionName: {
        type: String,
        required: true,
    },
    accounts: [accountSchema], // Use the defined accountSchema here
    lastSync: {
        type: Date,
        default: null,
    },
    transactionsCursor: {
        type: String,
        default: null,
    },
    syncLockUntil: {
        type: Date,
        default: null,
    },
    syncLockOwner: {
        type: String,
        default: null,
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'error'],
        default: 'active',
    },
    error: {
        type: String,
        default: null,
    },
}, {
    timestamps: true,
});

// Add index for faster queries
plaidItemSchema.index({ userId: 1, itemId: 1 }, { unique: true });

export const PlaidItem = mongoose.model('PlaidItem', plaidItemSchema); 